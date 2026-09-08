//! Local TTL cache for Factory billing limits to prevent redundant network requests and avoid risk control.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;

use super::config;
use super::models::{LimitsResponse, ProfileLimitsCache};

/// Try to load cached limits for `profile` if within TTL.
pub fn load_cache(cache_dir: &Path, profile: &str) -> Option<LimitsResponse> {
    let file = cache_dir.join(format!("{profile}.json"));
    if !file.is_file() {
        return None;
    }

    let content = fs::read_to_string(&file).ok()?;
    let cached: ProfileLimitsCache = serde_json::from_str(&content).ok()?;

    let now = Utc::now().timestamp();
    let ttl = config::cache_ttl_secs();
    if now.saturating_sub(cached.fetched_at) < ttl {
        Some(cached.limits)
    } else {
        None
    }
}

/// Save limits to cache for `profile` with current timestamp.
pub fn save_cache(cache_dir: &Path, profile: &str, limits: &LimitsResponse) -> Result<()> {
    fs::create_dir_all(cache_dir)
        .with_context(|| format!("create cache dir {}", cache_dir.display()))?;

    let file = cache_dir.join(format!("{profile}.json"));
    let entry = ProfileLimitsCache {
        fetched_at: Utc::now().timestamp(),
        limits: limits.clone(),
    };

    let content = serde_json::to_string(&entry).context("serialize limits cache")?;
    fs::write(&file, content).with_context(|| format!("write cache file {}", file.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_cache_roundtrip() {
        let dir = tempdir().unwrap();
        let limits = LimitsResponse {
            extra_usage_balance_cents: Some(100),
            ..Default::default()
        };

        save_cache(dir.path(), "test_prof", &limits).unwrap();
        let loaded = load_cache(dir.path(), "test_prof").expect("should load valid cache");
        assert_eq!(loaded.extra_usage_balance_cents, Some(100));
    }

    #[test]
    fn test_cache_expiry() {
        let dir = tempdir().unwrap();
        let limits = LimitsResponse::default();
        let file = dir.path().join("expired_prof.json");

        let entry = ProfileLimitsCache {
            fetched_at: Utc::now().timestamp() - 10000, // old timestamp
            limits,
        };
        fs::write(&file, serde_json::to_string(&entry).unwrap()).unwrap();

        let loaded = load_cache(dir.path(), "expired_prof");
        assert!(loaded.is_none(), "expired cache should return None");
    }
}

