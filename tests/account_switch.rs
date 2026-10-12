mod common;
use common::{read_profile, Sandbox};
use dsw::factory::identity_from_dir;
use predicates::prelude::*;

#[test]
fn manual_login_does_not_overwrite_the_outgoing_marker_profile() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");
    sb.cmd().args(["import", "main"]).assert().success();
    sb.write_live("bob@example.com");
    sb.cmd().args(["import", "work"]).assert().success();
    let work = read_profile(&sb.home, "work");
    // state.active says work, but Droid was manually logged in as Alice.
    sb.write_live("alice@example.com");
    sb.cmd().args(["use", "work"]).assert().success();
    assert_eq!(read_profile(&sb.home, "work"), work);
    assert_eq!(
        identity_from_dir(&sb.factory).email.as_deref(),
        Some("bob@example.com")
    );
}

#[test]
fn plain_sync_rejects_a_different_live_account() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");
    sb.cmd().args(["import", "main"]).assert().success();
    let before = read_profile(&sb.home, "main");
    sb.write_live("bob@example.com");
    sb.cmd()
        .args(["sync"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not match"));
    assert_eq!(read_profile(&sb.home, "main"), before);
}

#[test]
fn same_target_after_manual_login_repairs_active_marker() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");
    sb.cmd().args(["import", "main"]).assert().success();
    sb.write_live("bob@example.com");
    sb.cmd().args(["import", "work"]).assert().success();
    sb.write_live("alice@example.com");
    sb.cmd()
        .args(["use", "main"])
        .assert()
        .success()
        .stdout(predicate::str::contains("already on 'main'"));
    let output = sb.cmd().args(["status", "--json"]).output().unwrap();
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["active"], "main");
}
