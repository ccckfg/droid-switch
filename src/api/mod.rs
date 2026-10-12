//! Quota queries with persistent, identity-checked token refresh.

pub mod cache;
pub mod client;
pub mod config;
pub mod models;

use crate::auth::{self, accounts, storage::CredentialBundle};
use crate::paths::{Paths, CACHE_DIR};
use anyhow::Result;
pub use models::{LimitsResponse, PoolType, UsageSummary};

pub fn get_profile_usage(
    paths: &Paths,
    profile: &str,
    refresh: bool,
) -> Result<Option<UsageSummary>> {
    // The active marker may lag behind a manual /login. Read Droid's current
    // credentials without independently rotating its live refresh token.
    let is_live = accounts::sync_matching_live(paths, profile)?;
    if config::is_no_network() {
        return Ok(None);
    }
    let cache_dir = paths.home.join(CACHE_DIR);
    if !refresh {
        if let Some(cached) = cache::load_cache(&cache_dir, profile) {
            return Ok(Some(UsageSummary::from_limits(&cached)));
        }
    }
    let mut bundle = CredentialBundle::load(&paths.profile_dir(profile))?;
    if !is_live {
        auth::refresh_if_needed(&mut bundle, false)?;
    }
    let agent = client::create_agent();
    let limits = match client::fetch_limits(&agent, &bundle.tokens.access_token) {
        Ok(limits) => limits,
        Err(client::ApiError::Unauthorized) if !is_live => {
            auth::refresh_if_needed(&mut bundle, true)?;
            // Save before this request, even if the quota service fails.
            client::fetch_limits(&agent, &bundle.tokens.access_token)?
        }
        Err(client::ApiError::Unauthorized) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let _ = cache::save_cache(&cache_dir, profile, &limits);
    Ok(Some(UsageSummary::from_limits(&limits)))
}
