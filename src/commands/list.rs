use anyhow::Result;
use serde::Serialize;

use super::fmt_expiry;
use crate::api::{self, PoolType, UsageSummary};
use crate::cli::ListArgs;
use crate::factory::{identity_from_dir, Identity};
use crate::paths::{Paths, AUTH_FILES};
use crate::profile;
use crate::state::State;

#[derive(Serialize)]
struct Row {
    name: String,
    active: bool,
    email: Option<String>,
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<UsageSummary>,
}

struct RenderedRow<'a> {
    active: &'a str,
    name: &'a str,
    email: String,
    token: String,
    col1: String,
    col2: String,
    credits: String,
}

pub fn run(paths: &Paths, args: ListArgs) -> Result<()> {
    let names = profile::list(paths)?;
    let active = State::load(&paths.state_file())?.active;
    let pool_type = PoolType::from_args(args.pool.as_deref(), args.core);

    let rows: Vec<Row> = names
        .iter()
        .map(|name| {
            let id: Identity = identity_from_dir(&paths.profile_dir(name));
            let usage = api::get_profile_usage(paths, name, args.refresh);
            Row {
                name: name.clone(),
                active: active.as_deref() == Some(name.as_str()),
                email: id.email,
                expires_at: id.expires_at.map(|e| e.to_rfc3339()),
                usage,
            }
        })
        .collect();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    if rows.is_empty() {
        print_empty_state(paths);
        return Ok(());
    }

    print_rows(&rows, pool_type);
    Ok(())
}

fn print_empty_state(paths: &Paths) {
    println!("No profiles yet.");
    println!();
    if has_live_login(paths) {
        println!("A Droid login was found. Save it as your main profile:");
        println!("  dsw import main");
    } else {
        println!("No Droid login was found. Log in first, then save it:");
        println!("  droid");
        println!("  dsw import main");
        println!();
        println!("Or let dsw launch Droid for a new profile:");
        println!("  dsw add main");
    }
}

fn has_live_login(paths: &Paths) -> bool {
    AUTH_FILES.iter().any(|f| paths.factory.join(f).is_file())
}

fn print_rows(rows: &[Row], pool: PoolType) {
    let (h_col1, h_col2) = match pool {
        PoolType::Standard => ("5h(std)", "week(std)"),
        PoolType::Core => ("5h(core)", "week(core)"),
        PoolType::All => ("std(5h/wk)", "core(5h/wk)"),
    };

    let rendered: Vec<RenderedRow> = rows
        .iter()
        .map(|r| {
            let active = if r.active { "*" } else { " " };
            let email = r.email.clone().unwrap_or_else(|| "-".into());
            let token = r
                .expires_at
                .as_ref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|d| fmt_expiry(d.with_timezone(&chrono::Utc)))
                .unwrap_or_else(|| "-".into());

            let (col1, col2, credits) = match (&r.usage, pool) {
                (Some(u), PoolType::Standard) => (
                    UsageSummary::format_percent(u.std_5h),
                    UsageSummary::format_percent(u.std_weekly),
                    u.format_credits(),
                ),
                (Some(u), PoolType::Core) => (
                    UsageSummary::format_percent(u.core_5h),
                    UsageSummary::format_percent(u.core_weekly),
                    u.format_credits(),
                ),
                (Some(u), PoolType::All) => {
                    let std_str = format!(
                        "{}/{}",
                        UsageSummary::format_percent(u.std_5h),
                        UsageSummary::format_percent(u.std_weekly)
                    );
                    let core_str = format!(
                        "{}/{}",
                        UsageSummary::format_percent(u.core_5h),
                        UsageSummary::format_percent(u.core_weekly)
                    );
                    (std_str, core_str, u.format_credits())
                }
                (None, _) => ("-".into(), "-".into(), "-".into()),
            };

            RenderedRow {
                active,
                name: r.name.as_str(),
                email,
                token,
                col1,
                col2,
                credits,
            }
        })
        .collect();

    let name_w = rendered
        .iter()
        .map(|r| r.name.len())
        .max()
        .unwrap_or(0)
        .max("name".len());
    let email_w = rendered
        .iter()
        .map(|r| r.email.len())
        .max()
        .unwrap_or(0)
        .max("email".len());
    let token_w = rendered
        .iter()
        .map(|r| r.token.len())
        .max()
        .unwrap_or(0)
        .max("token".len());
    let col1_w = rendered
        .iter()
        .map(|r| r.col1.len())
        .max()
        .unwrap_or(0)
        .max(h_col1.len());
    let col2_w = rendered
        .iter()
        .map(|r| r.col2.len())
        .max()
        .unwrap_or(0)
        .max(h_col2.len());
    let credits_w = rendered
        .iter()
        .map(|r| r.credits.len())
        .max()
        .unwrap_or(0)
        .max("credits".len());

    println!(
        "  {:name_w$}  {:email_w$}  {:token_w$}  {:col1_w$}  {:col2_w$}  {:credits_w$}",
        "name", "email", "token", h_col1, h_col2, "credits"
    );
    println!(
        "  {:-<name_w$}  {:-<email_w$}  {:-<token_w$}  {:-<col1_w$}  {:-<col2_w$}  {:-<credits_w$}",
        "", "", "", "", "", ""
    );
    for r in rendered {
        println!(
            "{} {:name_w$}  {:email_w$}  {:token_w$}  {:col1_w$}  {:col2_w$}  {:credits_w$}",
            r.active, r.name, r.email, r.token, r.col1, r.col2, r.credits
        );
    }
}
