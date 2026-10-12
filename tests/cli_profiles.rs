mod common;
use common::{read_live, read_profile, Sandbox};
use dsw::factory::testing::write_synthetic_bundle;
use predicates::prelude::*;
use std::fs;

#[test]
fn sync_requires_live_auth_without_deleting_profile() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");
    sb.cmd().args(["import", "main"]).assert().success();
    for f in ["auth.v2.file", "auth.v2.key", "auth.encrypted"] {
        let _ = fs::remove_file(sb.factory.join(f));
    }

    sb.cmd()
        .args(["sync"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no auth files found"));

    sb.cmd()
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice@example.com"));
}

#[test]
fn sync_all_updates_matching_profiles_only() {
    let sb = Sandbox::new();

    sb.write_live("alice@example.com");
    sb.cmd().args(["import", "main"]).assert().success();
    let old_main = read_profile(&sb.home, "main");

    sb.write_live("bob@example.com");
    sb.cmd().args(["import", "work"]).assert().success();
    let old_work = read_profile(&sb.home, "work");

    sb.write_live("alice@example.com");
    let fresh_alice = read_live(&sb.factory);
    assert_ne!(fresh_alice, old_main);

    sb.cmd()
        .args(["sync", "--all"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 matching profile(s): main"));

    assert_eq!(read_profile(&sb.home, "main"), fresh_alice);
    assert_eq!(read_profile(&sb.home, "work"), old_work);
}

#[test]
fn sync_all_does_not_require_active_profile() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");

    sb.cmd()
        .args(["sync", "--all"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no matching profiles"));
}

#[test]
fn add_no_login_just_snapshots() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");
    sb.cmd()
        .args(["add", "main", "--no-login"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice@example.com"));
}

/// End-to-end exercise of the OAuth watcher: a fake `droid` (`sleep 60`) is
/// spawned, then a background thread writes a brand new bundle for a
/// different email into `~/.factory`. The watcher should detect the change,
/// SIGTERM the fake droid, and snapshot as the named profile - without the
/// user typing anything.

#[test]
fn add_watcher_detects_login_and_snapshots() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");

    // Background simulator: waits for the watcher to be ready, then writes a
    // bundle for a different email (simulates a successful OAuth login).
    let factory = sb.factory.clone();
    let ready_file = sb._td.path().join(".watcher-ready");
    let ready_clone = ready_file.clone();
    let sim = std::thread::spawn(move || {
        // Poll for up to 5s for the watcher to come up.
        for _ in 0..50 {
            if ready_clone.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        // Small extra delay so the watcher has at least one poll iteration
        // with the original `before_mtime`.
        std::thread::sleep(std::time::Duration::from_millis(50));
        for f in dsw::paths::AUTH_FILES {
            let _ = fs::remove_file(factory.join(f));
        }
        write_synthetic_bundle(&factory, "bob@example.com", 1_900_000_000);
    });

    let (sleep_bin, sleep_args) = if cfg!(windows) {
        (
            "powershell",
            "-NoProfile\u{1f}-Command\u{1f}Start-Sleep\u{1f}10",
        )
    } else {
        ("sleep", "10")
    };

    sb.cmd()
        .env("DSW_DROID_BIN", sleep_bin)
        .env("DSW_DROID_ARGS", sleep_args)
        .env("DSW_READY_FILE", &ready_file)
        .args(["add", "bob"])
        .timeout(std::time::Duration::from_secs(8))
        .assert()
        .success()
        .stdout(predicate::str::contains("bob@example.com"));

    sim.join().unwrap();

    // Verify the snapshot is on disk and active.
    sb.cmd()
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bob@example.com"));
}

#[test]
fn add_watcher_fails_when_droid_exits_without_login() {
    let sb = Sandbox::new();
    sb.write_live("alice@example.com");

    let (exit_bin, exit_args) = if cfg!(windows) {
        ("cmd", "/c\u{1f}exit\u{1f}0")
    } else {
        ("true", "")
    };

    sb.cmd()
        .env("DSW_DROID_BIN", exit_bin)
        .env("DSW_DROID_ARGS", exit_args)
        .args(["add", "newone"])
        .timeout(std::time::Duration::from_secs(5))
        .assert()
        .failure()
        .stderr(predicate::str::contains("no new login detected"));

    // Live bundle wasn't touched.
    sb.cmd()
        .args(["status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice@example.com"));
}

#[test]
fn keyring_bundle_switches_and_tracks_profile() {
    let sb = Sandbox::new();
    let key_b64 = dsw::factory::testing::write_synthetic_keyring_bundle(
        &sb.factory,
        "keyring_user@example.com",
        1_900_000_000,
    );

    sb.cmd()
        .env("FACTORY_ENCRYPTION_KEY", &key_b64)
        .args(["import", "keyring_prof"])
        .assert()
        .success()
        .stdout(predicate::str::contains("keyring_user@example.com"));

    // Verify list and status
    sb.cmd()
        .env("FACTORY_ENCRYPTION_KEY", &key_b64)
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("keyring_prof"))
        .stdout(predicate::str::contains("keyring_user@example.com"));

    // Verify file exists in profile dir
    assert!(sb
        .home
        .join("profiles/keyring_prof/auth.v2.keyring")
        .is_file());
}
