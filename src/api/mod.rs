//! API client module for Factory Droid quota limits and WorkOS authentication.

pub mod cache;
pub mod client;
pub mod config;
pub mod models;

use crate::factory;
use crate::paths::Paths;
pub use models::{LimitsResponse, PoolType, UsageSummary};


/// Retrieve usage summary for a profile, using local TTL cache when possible.
/// Returns `None` on network errors, missing tokens, or rate limit circuit break.
pub fn get_profile_usage(paths: &Paths, profile: &str, refresh: bool) -> Option<UsageSummary> {
    if config::is_no_network() {
        return None;
    }

    let cache_dir = paths.state_file().parent()?.join("cache");

    // 1. Try reading from cache unless refresh is requested
    if !refresh {
        if let Some(cached) = cache::load_cache(&cache_dir, profile) {
            return Some(UsageSummary::from_limits(&cached));
        }
    }

    // 2. Extract access & refresh tokens from profile directory
    let profile_dir = paths.profile_dir(profile);
    let tokens = factory::tokens_from_dir(&profile_dir)?;

    let agent = client::create_agent();

    // 3. Attempt to fetch limits with current access token
    let limits_result = client::fetch_limits(&agent, &tokens.access_token);

    let limits = match limits_result {
        Ok(limits) => limits,
        Err(client::ApiError::Unauthorized) => {
            // Access token expired, try refreshing via WorkOS if refresh_token exists
            if let Some(ref refresh_tok) = tokens.refresh_token {
                if let Ok(new_auth) = client::refresh_access_token(&agent, refresh_tok) {
                    client::fetch_limits(&agent, &new_auth.access_token).ok()?
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }
        Err(client::ApiError::RateLimited) => {
            // 429: Circuit break immediately, do not retry
            return None;
        }
        Err(_) => {
            return None;
        }
    };

    // 4. Update cache
    let _ = cache::save_cache(&cache_dir, profile, &limits);

    Some(UsageSummary::from_limits(&limits))
}
