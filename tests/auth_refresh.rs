mod common;
#[path = "common/http.rs"]
mod http;

use common::{read_live, read_profile, Sandbox};
use dsw::factory::{testing::make_jwt, tokens_from_dir};
use http::Server;
use predicates::prelude::*;
use serde_json::json;
use std::fs;

fn inactive(exp: i64) -> Sandbox {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");
    sb.cmd().args(["import", "main"]).assert().success();
    sb.write_live("bob@example.com");
    dsw::factory::testing::write_synthetic_bundle(&sb.factory, "bob@example.com", exp);
    sb.cmd().args(["import", "work"]).assert().success();
    sb.write_live("alice@example.com");
    sb
}

fn refreshed() -> serde_json::Value {
    json!({"access_token":make_jwt("bob@example.com",1_900_000_000),"refresh_token":"rotated-token"})
}

#[test]
fn list_persists_rotated_tokens_before_quota_failure() {
    let sb = inactive(1);
    let live = read_live(&sb.factory);
    let server = Server::start(vec![(200, json!({})), (200, refreshed()), (503, json!({}))]);
    sb.cmd()
        .env("DSW_NO_NETWORK", "0")
        .env("WORKOS_AUTH_URL", format!("{}/refresh", server.url))
        .env("FACTORY_API_BASE_URL", &server.url)
        .args(["list", "--refresh", "--json"])
        .assert()
        .success();
    let saved = tokens_from_dir(&sb.home.join("profiles/work")).unwrap();
    assert_eq!(saved.refresh_token.as_deref(), Some("rotated-token"));
    assert_eq!(saved.access_token, refreshed()["access_token"]);
    assert_eq!(read_live(&sb.factory), live);
    let requests = server.finish();
    assert!(requests[1].starts_with("POST /refresh"));
    assert!(requests[2].contains(&saved.access_token));
}

#[test]
fn switch_refreshes_expired_target_then_restores_new_bundle() {
    let sb = inactive(1);
    let server = Server::start(vec![(200, refreshed())]);
    sb.cmd()
        .env("DSW_NO_NETWORK", "0")
        .env("WORKOS_AUTH_URL", format!("{}/refresh", server.url))
        .args(["use", "work"])
        .assert()
        .success();
    let live = tokens_from_dir(&sb.factory).unwrap();
    assert_eq!(live.refresh_token.as_deref(), Some("rotated-token"));
    assert_eq!(read_live(&sb.factory), read_profile(&sb.home, "work"));
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn revoked_refresh_preserves_previous_live_account_and_profile() {
    let sb = inactive(1);
    let live = read_live(&sb.factory);
    let work = read_profile(&sb.home, "work");
    let state = fs::read(sb.home.join("state.json")).unwrap();
    let server = Server::start(vec![(400, json!({"error":"invalid_grant"}))]);
    sb.cmd()
        .env("DSW_NO_NETWORK", "0")
        .env("WORKOS_AUTH_URL", format!("{}/refresh", server.url))
        .args(["use", "work"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("login required"));
    assert_eq!(read_live(&sb.factory), live);
    assert_eq!(read_profile(&sb.home, "work"), work);
    assert_eq!(fs::read(sb.home.join("state.json")).unwrap(), state);
    server.finish();
}

#[test]
fn temporary_refresh_failure_does_not_destroy_credentials() {
    let sb = inactive(1);
    let work = read_profile(&sb.home, "work");
    let server = Server::start(vec![(503, json!({"error":"unavailable"}))]);
    sb.cmd()
        .env("DSW_NO_NETWORK", "0")
        .env("WORKOS_AUTH_URL", format!("{}/refresh", server.url))
        .args(["use", "work"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("token refresh failed"))
        .stderr(predicate::str::contains("login required").not());
    assert_eq!(read_profile(&sb.home, "work"), work);
    server.finish();
}

#[test]
fn list_does_not_rotate_the_current_droid_login() {
    let sb = Sandbox::new();
    dsw::factory::testing::write_synthetic_bundle(&sb.factory, "alice@example.com", 1);
    sb.cmd().args(["import", "main"]).assert().success();
    let live = read_live(&sb.factory);
    let server = Server::start(vec![(401, json!({}))]);
    let output = sb
        .cmd()
        .env("DSW_NO_NETWORK", "0")
        .env("WORKOS_AUTH_URL", format!("{}/refresh", server.url))
        .env("FACTORY_API_BASE_URL", &server.url)
        .args(["list", "--refresh", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows[0]["credential_status"], "access_expired");
    assert_eq!(read_live(&sb.factory), live);
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /api/billing/limits"));
}

#[test]
fn refresh_response_cannot_change_account_identity() {
    let sb = inactive(1);
    let work = read_profile(&sb.home, "work");
    let server = Server::start(vec![(
        200,
        json!({"access_token":make_jwt("mallory@example.com",1_900_000_000),"refresh_token":"other"}),
    )]);
    sb.cmd()
        .env("DSW_NO_NETWORK", "0")
        .env("WORKOS_AUTH_URL", format!("{}/refresh", server.url))
        .args(["use", "work"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("different account"));
    assert_eq!(read_profile(&sb.home, "work"), work);
    server.finish();
}

#[test]
fn two_switches_do_not_consume_the_same_refresh_token_twice() {
    let sb = inactive(1);
    let server = Server::start(vec![(200, refreshed())]);
    let mut commands = Vec::new();
    for _ in 0..2 {
        let mut command = sb.cmd();
        command
            .env("DSW_NO_NETWORK", "0")
            .env("WORKOS_AUTH_URL", format!("{}/refresh", server.url))
            .args(["use", "work"]);
        commands.push(command);
    }
    std::thread::scope(|scope| {
        let handles: Vec<_> = commands
            .into_iter()
            .map(|mut c| scope.spawn(move || c.output().unwrap()))
            .collect();
        for h in handles {
            let output = h.join().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    });
    assert_eq!(server.finish().len(), 1);
    assert_eq!(
        tokens_from_dir(&sb.factory)
            .unwrap()
            .refresh_token
            .as_deref(),
        Some("rotated-token")
    );
}

#[test]
fn quota_401_refreshes_an_inactive_profile_and_retries_once() {
    let sb = inactive(1_900_000_000);
    let server = Server::start(vec![
        (200, json!({})),
        (401, json!({})),
        (200, refreshed()),
        (200, json!({"extraUsageBalanceCents":125})),
    ]);
    sb.cmd()
        .env("DSW_NO_NETWORK", "0")
        .env("WORKOS_AUTH_URL", format!("{}/refresh", server.url))
        .env("FACTORY_API_BASE_URL", &server.url)
        .args(["list", "--refresh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("$1.25"));
    let saved = tokens_from_dir(&sb.home.join("profiles/work")).unwrap();
    assert_eq!(saved.refresh_token.as_deref(), Some("rotated-token"));
    assert_eq!(server.finish().len(), 4);
}
