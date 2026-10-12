//! Data models for Factory billing limits, WorkOS OAuth responses, and cached usage summaries.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LimitsResponse {
    pub uses_token_rate_limits_billing: Option<bool>,
    pub limits: Option<RateLimitsGroup>,
    pub overage_preference: Option<String>,
    pub can_manage_overage: Option<bool>,
    pub extra_usage_balance_cents: Option<i64>,
    pub extra_usage_allowed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitsGroup {
    pub standard: Option<PoolLimits>,
    pub core: Option<PoolLimits>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PoolLimits {
    pub five_hour: Option<WindowLimit>,
    pub weekly: Option<WindowLimit>,
    pub monthly: Option<WindowLimit>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WindowLimit {
    pub used_percent: Option<i64>,
    pub window_end: Option<String>,
    pub seconds_remaining: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkOsAuthResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileLimitsCache {
    pub fetched_at: i64,
    pub limits: LimitsResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolType {
    Standard,
    Core,
    All,
}

impl PoolType {
    pub fn from_args(pool: Option<&str>, core_flag: bool) -> Self {
        if core_flag {
            return PoolType::Core;
        }
        match pool.map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("core") => PoolType::Core,
            Some("all") => PoolType::All,
            _ => PoolType::Standard,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageSummary {
    pub std_5h: Option<i64>,
    pub std_weekly: Option<i64>,
    pub std_monthly: Option<i64>,
    pub core_5h: Option<i64>,
    pub core_weekly: Option<i64>,
    pub core_monthly: Option<i64>,
    pub credits_cents: Option<i64>,
}

impl UsageSummary {
    pub fn from_limits(resp: &LimitsResponse) -> Self {
        let std = resp.limits.as_ref().and_then(|l| l.standard.as_ref());
        let core = resp.limits.as_ref().and_then(|l| l.core.as_ref());

        Self {
            std_5h: std
                .and_then(|s| s.five_hour.as_ref())
                .and_then(|w| w.used_percent),
            std_weekly: std
                .and_then(|s| s.weekly.as_ref())
                .and_then(|w| w.used_percent),
            std_monthly: std
                .and_then(|s| s.monthly.as_ref())
                .and_then(|w| w.used_percent),
            core_5h: core
                .and_then(|c| c.five_hour.as_ref())
                .and_then(|w| w.used_percent),
            core_weekly: core
                .and_then(|c| c.weekly.as_ref())
                .and_then(|w| w.used_percent),
            core_monthly: core
                .and_then(|c| c.monthly.as_ref())
                .and_then(|w| w.used_percent),
            credits_cents: resp.extra_usage_balance_cents,
        }
    }

    pub fn format_percent(val: Option<i64>) -> String {
        match val {
            Some(p) => format!("{p}%"),
            None => "-".to_string(),
        }
    }

    pub fn format_credits(&self) -> String {
        match self.credits_cents {
            Some(cents) => format!("${:.2}", (cents as f64) / 100.0),
            None => "-".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_type_resolution() {
        assert_eq!(PoolType::from_args(None, false), PoolType::Standard);
        assert_eq!(PoolType::from_args(None, true), PoolType::Core);
        assert_eq!(PoolType::from_args(Some("core"), false), PoolType::Core);
        assert_eq!(PoolType::from_args(Some("all"), false), PoolType::All);
        assert_eq!(
            PoolType::from_args(Some("standard"), false),
            PoolType::Standard
        );
    }

    #[test]
    fn test_usage_summary_formatting() {
        let json_data = r#"{
            "usesTokenRateLimitsBilling": true,
            "limits": {
                "standard": {
                    "fiveHour": { "usedPercent": 15 },
                    "weekly": { "usedPercent": 45 },
                    "monthly": { "usedPercent": 60 }
                },
                "core": {
                    "fiveHour": { "usedPercent": 100 },
                    "weekly": { "usedPercent": 80 },
                    "monthly": { "usedPercent": 50 }
                }
            },
            "extraUsageBalanceCents": 250
        }"#;

        let resp: LimitsResponse = serde_json::from_str(json_data).unwrap();
        let summary = UsageSummary::from_limits(&resp);

        assert_eq!(summary.std_5h, Some(15));
        assert_eq!(summary.std_weekly, Some(45));
        assert_eq!(summary.core_5h, Some(100));
        assert_eq!(summary.format_credits(), "$2.50");
        assert_eq!(UsageSummary::format_percent(summary.std_5h), "15%");
        assert_eq!(UsageSummary::format_percent(None), "-");
    }
}
