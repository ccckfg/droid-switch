mod common;
use common::{read_live, Sandbox};
use dsw::factory::testing::write_legacy_bundle;
use predicates::prelude::*;

#[test]
fn import_then_status_then_list() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");

    sb.cmd()
        .args(["import", "main"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice@example.com"));

    sb.cmd()
        .args(["status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice@example.com"))
        .stdout(predicate::str::contains("main"));

    sb.cmd()
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("main"))
        .stdout(predicate::str::contains("alice@example.com"));
}

#[test]
fn no_args_suggests_import_when_live_login_exists() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");

    sb.cmd()
        .assert()
        .success()
        .stdout(predicate::str::contains("dsw import main"));
}

#[test]
fn no_args_suggests_login_when_no_live_login_exists() {
    let sb = Sandbox::new();

    sb.cmd()
        .assert()
        .success()
        .stdout(predicate::str::contains("No Droid login was found"))
        .stdout(predicate::str::contains("droid"))
        .stdout(predicate::str::contains("dsw add main"));
}

#[test]
fn empty_list_suggests_import_when_live_login_exists() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");

    sb.cmd()
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No profiles yet"))
        .stdout(predicate::str::contains("dsw import main"));
}

#[test]
fn empty_list_suggests_login_when_no_live_login_exists() {
    let sb = Sandbox::new();

    sb.cmd()
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No Droid login was found"))
        .stdout(predicate::str::contains("dsw add main"));
}

#[test]
fn switch_between_two_profiles_round_trips() {
    let sb = Sandbox::new();

    // 1. Save 'main' from alice.
    sb.write_live("alice@example.com");
    sb.cmd().args(["import", "main"]).assert().success();
    let alice_bytes = read_live(&sb.factory);

    // 2. Switch live to bob, save 'work'.
    sb.write_live("bob@example.com");
    sb.cmd().args(["import", "work"]).assert().success();
    let bob_bytes = read_live(&sb.factory);
    assert_ne!(alice_bytes, bob_bytes);

    // 3. Switch back to main; live bytes should match alice's snapshot.
    sb.cmd()
        .args(["use", "main"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice@example.com"));
    assert_eq!(read_live(&sb.factory), alice_bytes);

    // 4. Switch to work; bytes match bob's snapshot.
    sb.cmd()
        .args(["use", "work"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bob@example.com"));
    assert_eq!(read_live(&sb.factory), bob_bytes);
}

#[test]
fn use_unknown_profile_errors() {
    let sb = Sandbox::new();
    sb.cmd()
        .args(["use", "nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn import_force_overwrites() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");
    sb.cmd().args(["import", "main"]).assert().success();
    sb.write_live("bob@example.com");

    sb.cmd()
        .args(["import", "main"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));

    sb.cmd()
        .args(["import", "main", "--force"])
        .assert()
        .success();

    sb.cmd()
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bob@example.com"));
}

#[test]
fn rename_updates_active_marker() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");
    sb.cmd().args(["import", "main"]).assert().success();
    sb.cmd()
        .args(["rename", "main", "personal"])
        .assert()
        .success();
    sb.cmd()
        .args(["status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("personal"));
}

#[test]
fn remove_yes_clears_active() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");
    sb.cmd().args(["import", "main"]).assert().success();
    sb.cmd().args(["remove", "main", "-y"]).assert().success();
    sb.cmd()
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No profiles yet"));
}

#[test]
fn legacy_only_bundle_still_identified() {
    let sb = Sandbox::new();
    write_legacy_bundle(&sb.factory, "legacy@example.com", 1_900_000_000);
    sb.cmd().args(["import", "old"]).assert().success();
    sb.cmd()
        .args(["status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("legacy@example.com"));
}

#[test]
fn switch_creates_backup() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");
    sb.cmd().args(["import", "main"]).assert().success();
    sb.write_live("bob@example.com");
    sb.cmd().args(["import", "work"]).assert().success();

    // Switching from work -> main should create a backup of work's live state.
    sb.cmd().args(["use", "main"]).assert().success();

    sb.cmd()
        .args(["backup", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bob@example.com"));
}

#[test]
fn list_json_is_parseable() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");
    sb.cmd().args(["import", "main"]).assert().success();

    let out = sb.cmd().args(["list", "--json"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v.is_array());
    assert_eq!(v[0]["name"], "main");
    assert_eq!(v[0]["email"], "alice@example.com");
    assert_eq!(v[0]["active"], true);
}

#[test]
fn invalid_profile_name_rejected() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");
    sb.cmd()
        .args(["import", "Bad Name"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("profile name"));
}

#[test]
fn use_same_profile_is_idempotent() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");
    sb.cmd().args(["import", "main"]).assert().success();
    sb.cmd()
        .args(["use", "main"])
        .assert()
        .success()
        .stdout(predicate::str::contains("already on 'main'"));
}

#[test]
fn sync_updates_active_profile_from_live_auth() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");
    sb.cmd().args(["import", "main"]).assert().success();

    sb.write_live("alice@example.com");
    sb.cmd()
        .args(["sync"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice@example.com"));

    sb.cmd()
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice@example.com"));
}

#[test]
fn sync_requires_active_profile() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");

    sb.cmd()
        .args(["sync"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no active profile"));
}
