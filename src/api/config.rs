//! Configuration constants and environment variable overrides for Factory & WorkOS APIs.

use std::time::Duration;

pub const DEFAULT_FACTORY_API_URL: &str = "https://api.factory.ai";
pub const DEFAULT_WORKOS_AUTH_URL: &str = "https://api.workos.com/user_management/authenticate";
pub const DEFAULT_WORKOS_CLIENT_ID: &str = "client_01HNM792M5G5G1A2THWPXKFMXB";
pub const DEFAULT_USER_AGENT: &str = "droid/0.213.0";
pub const DEFAULT_TIMEOUT_SECS: u64 = 5;
pub const DEFAULT_CACHE_TTL_SECS: i64 = 300; // 5 minutes

pub fn factory_limits_url() -> String {
    let base = std::env::var("FACTORY_API_BASE_URL")
        .unwrap_or_else(|_| DEFAULT_FACTORY_API_URL.to_string());
    format!("{}/api/billing/limits", base.trim_end_matches('/'))
}

pub fn workos_auth_url() -> String {
    std::env::var("WORKOS_AUTH_URL").unwrap_or_else(|_| DEFAULT_WORKOS_AUTH_URL.to_string())
}

pub fn workos_client_id() -> String {
    std::env::var("WORKOS_CLIENT_ID").unwrap_or_else(|_| DEFAULT_WORKOS_CLIENT_ID.to_string())
}

pub fn user_agent() -> String {
    std::env::var("FACTORY_USER_AGENT").unwrap_or_else(|_| DEFAULT_USER_AGENT.to_string())
}

pub fn request_timeout() -> Duration {
    let secs = std::env::var("DSW_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

pub fn cache_ttl_secs() -> i64 {
    std::env::var("DSW_CACHE_TTL_SECS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(DEFAULT_CACHE_TTL_SECS)
}

pub fn is_no_network() -> bool {
    std::env::var("DSW_NO_NETWORK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}
