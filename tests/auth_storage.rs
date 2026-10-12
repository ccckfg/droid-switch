use std::fs;

use dsw::api::models::WorkOsAuthResponse;
use dsw::auth::storage::CredentialBundle;
use dsw::factory::{
    decrypt_v2,
    testing::{make_jwt, write_legacy_bundle, write_synthetic_bundle, write_synthetic_bundle_16iv},
};
use serde_json::json;
use tempfile::tempdir;

fn response() -> WorkOsAuthResponse {
    WorkOsAuthResponse {
        access_token: make_jwt("alice@example.com", 1_900_000_000),
        refresh_token: Some("rotated".into()),
    }
}

#[test]
fn encrypted_refresh_uses_new_nonce_and_remains_readable() {
    for iv16 in [false, true] {
        let td = tempdir().unwrap();
        if iv16 {
            write_synthetic_bundle_16iv(td.path(), "alice@example.com", 1);
        } else {
            write_synthetic_bundle(td.path(), "alice@example.com", 1);
        }
        let path = td.path().join("auth.v2.file");
        let original = fs::read_to_string(&path).unwrap();
        let mut bundle = CredentialBundle::load(td.path()).unwrap();
        bundle.persist_refresh(response()).unwrap();
        let stored = fs::read_to_string(&path).unwrap();
        assert_ne!(original.split(':').next(), stored.split(':').next());
        assert!(!stored.contains("rotated"));
        let decoded: serde_json::Value =
            serde_json::from_str(&decrypt_v2(&path, &td.path().join("auth.v2.key")).unwrap())
                .unwrap();
        assert_eq!(decoded["refresh_token"], "rotated");
    }
}

#[test]
fn refresh_preserves_unrecognized_credential_metadata() {
    let td = tempdir().unwrap();
    write_legacy_bundle(td.path(), "alice@example.com", 1);
    let path = td.path().join("auth.encrypted");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["organization"] = json!({"id":"org-test","region":"eu"});
    value["custom"] = json!([1, "keep", true]);
    fs::write(&path, value.to_string()).unwrap();
    let mut bundle = CredentialBundle::load(td.path()).unwrap();
    bundle.persist_refresh(response()).unwrap();
    let updated: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(updated["organization"], value["organization"]);
    assert_eq!(updated["custom"], value["custom"]);
    assert_eq!(updated["refresh_token"], "rotated");
}

#[test]
fn refresh_cannot_overwrite_a_concurrently_updated_file() {
    let td = tempdir().unwrap();
    write_synthetic_bundle(td.path(), "alice@example.com", 1);
    let mut bundle = CredentialBundle::load(td.path()).unwrap();
    write_synthetic_bundle(td.path(), "alice@example.com", 1_900_000_000);
    let path = td.path().join("auth.v2.file");
    let newer = fs::read(&path).unwrap();
    let error = bundle.persist_refresh(response()).unwrap_err();
    assert!(error.to_string().contains("changed during refresh"));
    assert_eq!(fs::read(path).unwrap(), newer);
}

#[test]
fn missing_rotated_refresh_token_does_not_replace_credentials() {
    let td = tempdir().unwrap();
    write_synthetic_bundle(td.path(), "alice@example.com", 1);
    let path = td.path().join("auth.v2.file");
    let original = fs::read(&path).unwrap();
    let mut bundle = CredentialBundle::load(td.path()).unwrap();
    let mut auth = response();
    auth.refresh_token = None;
    assert!(bundle.persist_refresh(auth).is_err());
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn refreshed_keyring_takes_precedence_over_a_stale_legacy_file() {
    let td = tempdir().unwrap();
    write_synthetic_bundle(td.path(), "alice@example.com", 1);
    let legacy = td.path().join("auth.v2.file");
    let keyring = td.path().join("auth.v2.keyring");
    fs::copy(&legacy, &keyring).unwrap();
    let before = fs::read(&legacy).unwrap();
    let mut bundle = CredentialBundle::load(td.path()).unwrap();
    bundle.persist_refresh(response()).unwrap();
    assert_eq!(fs::read(&legacy).unwrap(), before);
    let loaded = CredentialBundle::load(td.path()).unwrap();
    assert_eq!(loaded.tokens.refresh_token.as_deref(), Some("rotated"));
    let decoded = decrypt_v2(&keyring, &td.path().join("auth.v2.key")).unwrap();
    assert!(decoded.contains("rotated"));
}
