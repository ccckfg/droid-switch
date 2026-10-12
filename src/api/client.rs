//! HTTP client for Factory billing limits and WorkOS token refresh.

use thiserror::Error;

use super::config;
use super::models::{LimitsResponse, WorkOsAuthResponse};

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("unauthorized (401)")]
    Unauthorized,
    #[error(
        "login required: refresh token expired or was revoked; log in with droid and import again"
    )]
    LoginRequired,
    #[error("rate limited (429)")]
    RateLimited,
    #[error("HTTP error {0}: {1}")]
    Http(u16, String),
    #[error("network error: {0}")]
    Network(String),
    #[error("JSON parse error: {0}")]
    Parse(String),
}

pub fn create_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(config::request_timeout()))
        .build()
        .new_agent()
}

/// Fetch billing limits from Factory API using `access_token`.
pub fn fetch_limits(agent: &ureq::Agent, access_token: &str) -> Result<LimitsResponse, ApiError> {
    let url = config::factory_limits_url();
    let resp = agent
        .get(&url)
        .header("User-Agent", &config::user_agent())
        .header("Accept", "application/json")
        .header("Authorization", &format!("Bearer {}", access_token.trim()))
        .call()
        .map_err(|e| match e {
            ureq::Error::StatusCode(401) => ApiError::Unauthorized,
            ureq::Error::StatusCode(429) => ApiError::RateLimited,
            ureq::Error::StatusCode(code) => ApiError::Http(code, format!("status code {code}")),
            other => ApiError::Network(other.to_string()),
        })?;

    match resp.status().as_u16() {
        200..=299 => {}
        401 => return Err(ApiError::Unauthorized),
        429 => return Err(ApiError::RateLimited),
        code => return Err(ApiError::Http(code, format!("status code {code}"))),
    }
    resp.into_body()
        .read_json::<LimitsResponse>()
        .map_err(|e| ApiError::Parse(e.to_string()))
}

/// Refresh access token via WorkOS using `refresh_token`.
pub fn refresh_access_token(
    agent: &ureq::Agent,
    refresh_token: &str,
) -> Result<WorkOsAuthResponse, ApiError> {
    let url = config::workos_auth_url();
    let body = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}",
        url_encode(refresh_token.trim()),
        url_encode(&config::workos_client_id())
    );

    let resp = agent
        .post(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("User-Agent", &config::user_agent())
        .send(body.as_bytes())
        .map_err(|e| match e {
            ureq::Error::StatusCode(401) => ApiError::Unauthorized,
            ureq::Error::StatusCode(429) => ApiError::RateLimited,
            ureq::Error::StatusCode(code) => ApiError::Http(code, format!("status code {code}")),
            other => ApiError::Network(other.to_string()),
        })?;

    let status = resp.status().as_u16();
    if !(200..=299).contains(&status) {
        let value: serde_json::Value = resp.into_body().read_json().unwrap_or_default();
        let code = value.get("error").and_then(|v| v.as_str());
        return Err(match (status, code) {
            (400, Some("invalid_grant" | "refresh_token_revoked" | "invalid_refresh_token"))
            | (401, _) => ApiError::LoginRequired,
            (429, _) => ApiError::RateLimited,
            _ => ApiError::Http(status, "token refresh failed".into()),
        });
    }
    resp.into_body()
        .read_json::<WorkOsAuthResponse>()
        .map_err(|_| ApiError::Parse("invalid token refresh response".into()))
}

fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{:02X}", b);
            }
        }
    }
    out
}
